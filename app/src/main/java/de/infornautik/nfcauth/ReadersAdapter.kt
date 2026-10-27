package de.infornautik.nfcauth

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView

class ReadersAdapter(private val onReaderClick: (ReaderInfo) -> Unit) :
    ListAdapter<ReaderInfo, ReadersAdapter.ReaderViewHolder>(ReaderDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ReaderViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(android.R.layout.simple_list_item_2, parent, false)
        return ReaderViewHolder(view)
    }

    override fun onBindViewHolder(holder: ReaderViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class ReaderViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val title: TextView = itemView.findViewById(android.R.id.text1)
        private val subtitle: TextView = itemView.findViewById(android.R.id.text2)

        fun bind(reader: ReaderInfo) {
            title.text = reader.serviceName
            subtitle.text = itemView.context.getString(
                R.string.service_list_verified,
                reader.operatorName + " · " + reader.authenticationProfile,
            )
            itemView.setOnClickListener { onReaderClick(reader) }
        }
    }

    private class ReaderDiffCallback : DiffUtil.ItemCallback<ReaderInfo>() {
        override fun areItemsTheSame(oldItem: ReaderInfo, newItem: ReaderInfo): Boolean =
            oldItem.serviceOrigin == newItem.serviceOrigin &&
                oldItem.serviceId == newItem.serviceId &&
                oldItem.authenticationProfile == newItem.authenticationProfile

        override fun areContentsTheSame(oldItem: ReaderInfo, newItem: ReaderInfo): Boolean =
            oldItem == newItem
    }
}
